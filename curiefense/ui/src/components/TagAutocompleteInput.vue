<template>

  <autocomplete-input
      :suggestions="tagsSuggestions"
      :initial-value="initialTag"
      :clear-input-after-selection="clearInputAfterSelection"
      :auto-focus="autoFocus"
      :selection-type="selectionType"
      :minimum-value-length="minimumTagLength"
      @value-changed="tagChanged"
      @value-submitted="tagSubmitted"
      @keyup="bubbleEvent('keyup', $event)"
      @keydown="bubbleEvent('keydown', $event)"
      @keypress="bubbleEvent('keypress', $event)"
      @focus="bubbleEvent('focus', $event)"
      @blur="bubbleEvent('blur', $event)"/>

</template>

<script lang="ts">
import _ from 'lodash'
import RequestsUtils from '@/assets/RequestsUtils.ts'
import AutocompleteInput, {AutocompleteInputEvents, AutocompleteSuggestion} from '@/components/AutocompleteInput.vue'
import Vue from 'vue'
import {AxiosResponse} from 'axios'
import {TagsDatabaseDocument} from '@/types'

export default Vue.extend({
  name: 'TagAutocompleteInput',

  components: {
    AutocompleteInput,
  },

  props: {
    initialTag: {
      type: String,
      default: '',
    },
    clearInputAfterSelection: {
      type: Boolean,
      default: false,
    },
    autoFocus: {
      type: Boolean,
      default: false,
    },
    selectionType: {
      type: String,
      validator(val) {
        if (!val) {
          return false
        }
        return ['single', 'multiple'].includes(val.toLowerCase())
      },
      default: 'single',
    },
  },

  data() {
    const defaultKeyData = {
      legitimate: [] as string[],
      malicious: [] as string[],
      neutral: [] as string[],
    }
    return {
      tag: this.initialTag,
      open: false,
      tagsSuggestions: [] as AutocompleteSuggestion[],
      focusedSuggestionIndex: -1,
      db: 'system',
      key: 'tags',
      defaultKeyData: defaultKeyData,
      defaultDatabaseData: {
        tags: defaultKeyData,
      },
      minimumTagLength: 3,

      apiRoot: RequestsUtils.confAPIRoot,
      apiVersion: RequestsUtils.confAPIVersion,
    }
  },

  computed: {

    currentTag(): string {
      let currentTag
      if (this?.selectionType.toLowerCase() === 'multiple') {
        const tags = this.tag.split(' ')
        currentTag = tags[tags.length - 1].trim()
      } else {
        currentTag = this.tag.trim()
      }
      return currentTag
    },

  },

  methods: {

    loadAutocompleteSuggestions() {
      RequestsUtils.sendRequest('GET',
          `db/${this.db}/k/${this.key}/`).then((response: AxiosResponse<TagsDatabaseDocument>) => {
        this.buildTagsSuggestionsFromData(response.data)
      }).catch(() => {
        // key does not exist, check if db exists
        RequestsUtils.sendRequest('GET', `db/${this.db}/`).then(() => {
          // db exits, key does not exist -> create a key
          RequestsUtils.sendRequest('PUT', `db/${this.db}/k/${this.key}/`, this.defaultKeyData)
        }).catch(() => {
          // db doest not exist, key does not exist -> create a db with key
          RequestsUtils.sendRequest('POST', `db/${this.db}/`, this.defaultDatabaseData)
        })
      })
    },

    buildTagsSuggestionsFromData(data: TagsDatabaseDocument) {
      data = {...this.defaultKeyData, ...data}
      const legitimateTags = data.legitimate.map((item: string) => {
        return {
          prefix: '<span class="dot legitimate" title="legitimate"></span>',
          value: item,
        }
      })
      const maliciousTags = data.malicious.map((item: string) => {
        return {
          prefix: '<span class="dot malicious" title="malicious"></span>',
          value: item,
        }
      })
      const neutralTags = data.neutral.map((item: string) => {
        return {
          prefix: '<span class="dot neutral" title="neutral"></span>',
          value: item,
        }
      })
      this.tagsSuggestions = [].concat(legitimateTags, maliciousTags, neutralTags) as AutocompleteSuggestion[]
      this.tagsSuggestions = _.sortBy(this.tagsSuggestions, 'value') as AutocompleteSuggestion[]
    },

    bubbleEvent(eventName: AutocompleteInputEvents, event: Event) {
      this.$emit(eventName, event)
    },

    tagChanged(newTag: string) {
      this.tag = newTag
      this.$emit('tag-changed', this.tag)
    },

    tagSubmitted(newTag: string) {
      this.tag = newTag
      // if submitting a tag we don't recognize -> add it to the DB
      if (!this.tagsSuggestions.find((suggestion) => {
        return suggestion.value === this.currentTag.toLowerCase()
      })) {
        this.addUnknownTagToDB(this.currentTag)
      }
      this.$emit('tag-submitted', this.tag)
    },

    async addUnknownTagToDB(tag: string) {
      tag = tag.toLowerCase()
      // get current tags from db
      const response = await RequestsUtils.sendRequest('GET', `db/${this.db}/k/${this.key}/`)
      const document = {...this.defaultKeyData, ...response.data}
      // add new tag to neutral group
      document.neutral.push(tag)
      // save to DB
      RequestsUtils.sendRequest('PUT', `db/${this.db}/k/${this.key}/`, document).then(() => {
        // rebuild the tags suggestion list after a successful save
        this.buildTagsSuggestionsFromData(document)
        console.log(`saved tag [${tag}] to database, it will now be available for autocomplete!`)
      })
    },

  },

  created() {
    this.loadAutocompleteSuggestions()
  },
})
</script>
<style scoped lang="scss">

@import 'node_modules/bulma/sass/utilities/initial-variables.sass';
@import 'node_modules/bulma/sass/utilities/functions.sass';
@import 'node_modules/bulma/sass/utilities/derived-variables.sass';
@import 'node_modules/bulma/sass/helpers/color.sass';

::v-deep .dot {
  @extend .has-background-info;
  border-radius: 50%;
  display: inline-block;
  height: 0.5rem;
  margin-left: -0.25rem;
  margin-right: 0.25rem;
  width: 0.5rem;
}

::v-deep .dot.legitimate {
  @extend .has-background-success;
}

::v-deep .dot.malicious {
  @extend .has-background-danger;
}

::v-deep .dot.neutral {
  @extend .has-background-grey-light ;
}
</style>
